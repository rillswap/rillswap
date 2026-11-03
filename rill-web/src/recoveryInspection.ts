/**
 * Offline RS-007 inspection and disconnected forward refunds/reverse claims.
 * Inspection proves internal consistency under embedded signers, not provenance,
 * ownership, chain inclusion, unspent state, or authority to sign/broadcast.
 * Constructors produce broadcastable spending bytes. Reverse claim witnesses
 * disclose the preimage. Future callers MUST
 * obtain explicit approval before signing/export, not only before broadcasting.
 * Inspection reports and errors contain no secrets. Spending results contain
 * authorized transaction bytes; fallback successors are secret-bearing bytes
 * for local encryption only. Immutable parsed strings cannot
 * be guaranteed erased from browser memory. There are no live-time gates.
 */
import { schnorr, secp256k1 } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, concatBytes, hexToBytes } from "@noble/hashes/utils.js";
import mainnet from "./networks/mainnet.json" with { type: "json" };
import signet from "./networks/signet.json" with { type: "json" };
import testnet4 from "./networks/testnet4.json" with { type: "json" };
import regtest from "./networks/regtest-rillswap-e2e-v1.json" with { type: "json" };
import { validateNetwork } from "./generated/manualAdvertisementValidators.js";
import { parseRecoveryPlaintext } from "./recoveryDocument";
import { COOPERATIVE_RESERVATION_EXTENSION, verifyCooperativeClaimProposal } from "./swap/cooperative";
import type { FundingBinding } from "./swap/funding";
import { checkFeeBreakdown, FEE_POLICY_FEATURE } from "./swap/feePolicy";
import {
  clientAcceptanceHash, contractHash, epochBoundSessionId, fundingBindingHash, handshakeAcceptHash,
  handshakeHash, handshakeInitHash, jcs, providerTermsHash, taggedHash, unsignedEnvelopeHash,
} from "./swap/hashes";
import { reconstructTaprootContract, type TaprootContract } from "./swap/taproot";
import { MAX_TRANSACTION_BYTES, parseRecoveryFundingTransaction, parseTransaction, serializeTransaction, type Transaction } from "./swap/transaction";
import {
  COOPERATIVE_CLAIM_FEATURE, EPOCH_SESSION_EXTENSION, EPOCH_SESSION_FEATURE, MAX_SATS, sats, signedSats,
  verifySchnorr, type BtcToLnTerms, type LnToBtcTerms, type HandshakeAccept, type HandshakeInit,
} from "./swap/wire";

export interface RecoveryInspection {
  readonly destinationScript: string;
  readonly maxRefundFeeSat: string;
  readonly verification: "historical-static";
  readonly networkName: string;
  readonly profileId: "btc-to-ln/v1";
  readonly contractHash: string;
  readonly refundLockHeight: number;
  readonly firstRefundEligibleHeight: number;
  /** Signed revisions, NOT evidence that any output actually exists or is unspent. */
  readonly recordedBindingCount: number;
  /** Embedded signed history, not provenance, transaction, or UTXO evidence. */
  readonly fundingHistory: readonly RecoveryFundingBinding[];
}

export class RecoveryInspectionRefusedError extends Error {
  constructor() {
    super("Recovery document could not be authenticated");
    this.name = "RecoveryInspectionRefusedError";
  }
}

export interface RecoveryFundingBinding extends Omit<FundingBinding, "binding_revision" | "replaces_txid" | "funder_role"> {
  readonly binding_revision: number;
  readonly replaces_txid: string | null;
  readonly funder_role: "client" | "provider";
}
type HistoricalBinding = RecoveryFundingBinding;

/** Only used after bounded, canonical admission has checked every field's shape. */
interface RecoveryRecord {
  readonly network_identity: { readonly name: string; readonly deployment_namespace: string | null };
  readonly profile_id: string;
  readonly contract_hash: string;
  readonly created_at: number;
  readonly updated_at: number;
  readonly contract_terms: BtcToLnTerms | LnToBtcTerms;
  readonly verification_context: {
    readonly handshake_init: HandshakeInit;
    readonly handshake_accept: HandshakeAccept;
    readonly provider_identity_signature: string;
    readonly handshake_hash: string;
    readonly client_session_xonly_key: string;
    readonly provider_session_xonly_key: string;
    readonly provider_terms_signature: string;
    readonly client_acceptance_signature: string;
  };
  readonly taproot_contract: TaprootContract;
  readonly user_secret: { readonly contract_secret_key: string };
  readonly funding_history: readonly { readonly binding: HistoricalBinding; readonly funder_session_signature: string }[];
  readonly chain_scan_birthday_height: number;
  readonly recovery_authorization_xonly_key: string;
  readonly fee_policy: { readonly max_claim_fee_sat: string; readonly max_refund_fee_sat: string };
  readonly monotonic_knowledge: { readonly preimage_known: boolean; readonly preimage: string | null };
  readonly extensions: Readonly<Record<string, unknown>>;
}

const same = (left: unknown, right: unknown): boolean => bytesToHex(jcs(left)) === bytesToHex(jcs(right));
function require(condition: boolean): void {
  if (!condition) throw new RecoveryInspectionRefusedError();
}

function curveKey(key: string, compressed = false): void {
  // Schema establishes exact lowercase encoding; SEC point decoding establishes curve membership.
  secp256k1.Point.fromBytes(hexToBytes(compressed ? key : `02${key}`)).assertValidity();
}

function features(list: readonly string[], supported: readonly string[]): void {
  require(list.every((item, i) => supported.includes(item) && (i === 0 || list[i - 1]! < item)));
}

/** Historical model/validate_against rules, intentionally NOT the live admission helper. */
function checkHandshake(record: RecoveryRecord): void {
  const { handshake_init: init, handshake_accept: accept } = record.verification_context;
  const supported = [COOPERATIVE_CLAIM_FEATURE, EPOCH_SESSION_FEATURE, FEE_POLICY_FEATURE];
  features(init.required_features, supported);
  features(accept.required_features, supported);
  features(record.contract_terms.required_features, [COOPERATIVE_CLAIM_FEATURE, FEE_POLICY_FEATURE]);
  for (const feature of supported) {
    require(init.required_features.includes(feature) === accept.required_features.includes(feature));
  }
  require(record.contract_terms.required_features.includes(COOPERATIVE_CLAIM_FEATURE) === init.required_features.includes(COOPERATIVE_CLAIM_FEATURE));
  require(record.contract_terms.required_features.includes(FEE_POLICY_FEATURE) === init.required_features.includes(FEE_POLICY_FEATURE));
  require(init.session_id !== init.client_challenge && init.client_session_xonly_key !== init.expected_provider_identity_xonly_key);
  require(new Set([accept.client_session_xonly_key, accept.provider_session_xonly_key, accept.provider_identity_xonly_key]).size === 3);
  require(![accept.session_id, accept.client_challenge].includes(accept.provider_challenge));
  const echoed = ["protocol", "wire_version", "profile_id", "network_identity", "session_id", "client_challenge", "client_session_xonly_key"] as const;
  require(echoed.every((field) => same(accept[field], init[field])));
  require(accept.handshake_init_hash === bytesToHex(handshakeInitHash(init)));
  require(accept.provider_identity_xonly_key === init.expected_provider_identity_xonly_key);
  require(init.requested_encryption_suites.includes(accept.selected_encryption_suite));
  require(accept.selected_capabilities.every((item) => init.requested_capabilities.includes(item)));
  for (const key of [init.client_session_xonly_key, init.expected_provider_identity_xonly_key,
    accept.client_session_xonly_key, accept.provider_session_xonly_key, accept.provider_identity_xonly_key]) curveKey(key);
  // Every session is bound to one provider epoch; its session ID commits to it.
  require(init.required_features.includes(EPOCH_SESSION_FEATURE));
  const extension = init.extensions[EPOCH_SESSION_EXTENSION];
  require(extension !== null && typeof extension === "object" && !Array.isArray(extension));
  const object = extension as Record<string, unknown>;
  require(Object.keys(object).length === 1 && typeof object.epoch_inbox_xonly_key === "string");
  const epoch = object.epoch_inbox_xonly_key as string;
  require(/^[0-9a-f]{64}$/.test(epoch));
  curveKey(epoch);
  require(accept.provider_session_xonly_key !== epoch);
  require(init.session_id === bytesToHex(epochBoundSessionId(init.network_identity, init.expected_provider_identity_xonly_key, epoch, init.client_session_xonly_key)));
}

function checkTerms(terms: BtcToLnTerms | LnToBtcTerms): void {
  checkFeeBreakdown(terms);
  // The parser already enforced the closed schema, including profile roles, networks, lists, and extensions.
  let principal: bigint;
  if (terms.profile_id === "btc-to-ln/v1") {
    require(terms.economics.kind === "btc-to-ln" && terms.timing_policy.kind === "btc-to-ln" && terms.claimant === "provider" && terms.refund_party === "client");
    principal = sats(terms.economics.lightning_principal_sat, "principal", true);
    const fee = signedSats(terms.economics.success_fee_sat, "success fee");
    require(principal + fee === sats(terms.economics.contract_amount_sat, "contract amount", true));
    require(terms.timing_policy.max_outgoing_htlc_expiry_height + terms.timing_policy.learn_and_claim_blocks < terms.refund_lock_height + 1);
  } else {
    require(terms.profile_id === "ln-to-btc/v1" && terms.economics.kind === "ln-to-btc" && terms.timing_policy.kind === "ln-to-btc" && terms.claimant === "client" && terms.refund_party === "provider");
    const e = terms.economics, value = sats(e.contract_amount_sat, "value", true), payout = sats(e.nominal_payout_sat, "payout", true),
      reserve = sats(e.claim_fee_reserve_sat, "reserve"), fee = signedSats(e.success_fee_sat, "fee"), prepayment = sats(e.mining_prepayment_sat, "prepayment");
    principal = sats(e.hold_invoice_sat, "hold", true);
    // This browser supports no mining prepayment, historical or live.
    require(prepayment === 0n && value === payout + reserve && value + fee <= MAX_SATS && principal === value + fee);
    require(terms.refund_lock_height + 1 + terms.timing_policy.refund_and_ln_resolution_blocks < terms.timing_policy.min_incoming_htlc_expiry_height);
  }
  for (const value of [terms.max_funding_fee_sat, terms.max_claim_fee_sat, terms.max_refund_fee_sat]) sats(value, "fee cap");
  for (const key of [terms.client_contract_compressed_key, terms.provider_contract_compressed_key, terms.invoice_binding.payee_compressed_pubkey]) curveKey(key, true);
  curveKey(terms.provider_identity_key);
  curveKey(terms.recovery_authorization_xonly_key);
  const invoice = terms.invoice_binding;
  const msats = BigInt(invoice.amount_msat);
  require(msats > 0n && msats <= MAX_SATS * 1000n && msats === principal * 1000n && invoice.expires_at > invoice.created_at);
  const destination = /^(0014[0-9a-f]{40}|5120[0-9a-f]{64})$/;
  require(destination.test(terms.client_destination_script) && destination.test(terms.provider_destination_script));
}

function checkHistory(record: RecoveryRecord): void {
  const history = record.funding_history;
  const seen = new Set<string>();
  for (const [revision, item] of history.entries()) {
    const binding = item.binding;
    require(binding.contract_hash === record.contract_hash && binding.funder_role === (record.profile_id === "ln-to-btc/v1" ? "provider" : "client") && binding.binding_revision === revision);
    require(sats(binding.contract_value_sat, "funding value", true) === BigInt(record.contract_terms.economics.contract_amount_sat));
    require(binding.contract_script_pubkey === record.taproot_contract.script_pubkey);
    require(binding.contract_vout <= 0xffffffff && binding.lineage_anchor_vout <= 0xffffffff);
    require(!seen.has(binding.funding_txid));
    seen.add(binding.funding_txid);
    if (revision === 0) require(binding.replaces_txid === null);
    else {
      const previous = history[revision - 1]!.binding;
      require(binding.replaces_txid === previous.funding_txid && binding.funding_attempt_id === previous.funding_attempt_id);
      require(binding.lineage_anchor_txid === previous.lineage_anchor_txid && binding.lineage_anchor_vout === previous.lineage_anchor_vout);
    }
    verifySchnorr(record.profile_id === "ln-to-btc/v1" ? record.verification_context.provider_session_xonly_key : record.verification_context.client_session_xonly_key,
      fundingBindingHash(binding), item.funder_session_signature, "funding");
  }
}

interface Reservation {
  readonly signature_hash: string;
  readonly proposal: Record<string, unknown> & {
    readonly required_features: readonly string[];
    readonly signature: string | null;
    readonly payload: Record<string, unknown>;
  };
}

/** Historical proposal authentication is shared; callers select the original claimant role and binding. */
function checkHistoricalProposal(record: RecoveryRecord, proposal: Reservation["proposal"], signer: string): Record<string, unknown> {
  const context = record.verification_context;
  require(record.funding_history.length > 0 && record.monotonic_knowledge.preimage_known);
  features(proposal.required_features, [COOPERATIVE_CLAIM_FEATURE, EPOCH_SESSION_FEATURE]);
  require(record.contract_terms.required_features.includes(COOPERATIVE_CLAIM_FEATURE) && proposal.required_features.includes(COOPERATIVE_CLAIM_FEATURE));
  require(proposal.session_id === context.handshake_init.session_id && proposal.profile_id === record.profile_id);
  require(same(proposal.network_identity, record.network_identity) && proposal.sender_session_key === signer);
  require(proposal.message_type === "action_request" && proposal.contract_hash === record.contract_hash && proposal.in_reply_to === null);
  require(proposal.signature !== null);
  verifySchnorr(signer, unsignedEnvelopeHash(proposal), proposal.signature!, "reservation");
  const payload = proposal.payload;
  const fields = ["action", "cooperation_id", "payment_preimage", "public_nonce", "unsigned_transaction", "deadline_at", "deadline_height"];
  require(Object.keys(payload).length === fields.length && fields.every((field) => Object.hasOwn(payload, field)));
  require(payload.action === "cooperative_claim_propose");
  for (const field of ["cooperation_id", "payment_preimage"]) require(typeof payload[field] === "string" && /^[0-9a-f]{64}$/.test(payload[field] as string));
  require(typeof payload.public_nonce === "string" && /^[0-9a-f]{132}$/.test(payload.public_nonce));
  require(typeof payload.unsigned_transaction === "string" && /^(?:[0-9a-f]{2}){60,1000}$/.test(payload.unsigned_transaction));
  require(typeof payload.deadline_at === "number" && Number.isSafeInteger(payload.deadline_at) && payload.deadline_at > 0);
  require(typeof payload.deadline_height === "number" && Number.isSafeInteger(payload.deadline_height) && payload.deadline_height > 0 &&
    payload.deadline_height <= record.contract_terms.refund_lock_height - record.contract_terms.timing_policy.claim_confirmation_blocks);
  require(payload.payment_preimage === record.monotonic_knowledge.preimage);
  return payload;
}

function checkReservation(record: RecoveryRecord): void {
  if (!Object.hasOwn(record.extensions, COOPERATIVE_RESERVATION_EXTENSION)) return;
  const reservation = record.extensions[COOPERATIVE_RESERVATION_EXTENSION] as Reservation;
  const payload = checkHistoricalProposal(record, reservation.proposal, record.verification_context.provider_session_xonly_key);
  let matches = 0;
  for (const { binding } of record.funding_history) {
    let digest: string;
    try {
      digest = bytesToHex(verifyCooperativeClaimProposal(hexToBytes(payload.unsigned_transaction as string), record.contract_terms as BtcToLnTerms, binding).signatureHash);
    } catch { continue; } // Another retained revision may be the proposal's original outpoint.
    require(digest === reservation.signature_hash);
    matches++;
  }
  require(matches === 1);
}

function checkReverseCooperation(record: RecoveryRecord): void {
  const hasBurn = Object.hasOwn(record.extensions, REVERSE_COOPERATIVE_RESERVATION_EXTENSION);
  const hasDisclosure = Object.hasOwn(record.extensions, REVERSE_DISCLOSURE_EXTENSION);
  if (!hasBurn && !hasDisclosure) return;
  // The fallback is independently authenticated before any historical marker.
  require(Object.hasOwn(record.extensions, REVERSE_FALLBACK_EXTENSION));
  const fallback = record.extensions[REVERSE_FALLBACK_EXTENSION] as { funding_binding_hash: string };
  const burn = record.extensions[REVERSE_COOPERATIVE_RESERVATION_EXTENSION] as { funding_binding_hash: string; cooperation_id: string };
  if (hasBurn) require(burn.funding_binding_hash === fallback.funding_binding_hash && burn.cooperation_id !== "00".repeat(32));
  if (!hasDisclosure) return;
  const disclosure = record.extensions[REVERSE_DISCLOSURE_EXTENSION] as { funding_binding_hash: string; proposal: Reservation["proposal"] };
  require(disclosure.funding_binding_hash === fallback.funding_binding_hash);
  const payload = checkHistoricalProposal(record, disclosure.proposal, record.verification_context.client_session_xonly_key);
  if (hasBurn) require(payload.cooperation_id === burn.cooperation_id);
  const matches = record.funding_history.filter(({ binding }) => bytesToHex(fundingBindingHash(binding)) === disclosure.funding_binding_hash);
  require(matches.length === 1);
  verifyCooperativeClaimProposal(hexToBytes(payload.unsigned_transaction as string), record.contract_terms as LnToBtcTerms, matches[0]!.binding);
  // Expiry, the latest binding, and publication order are live/successor gates,
  // not historical facts inferred from an imported record. No nonce is restored.
}

/** Private secret-bearing state. Every public operation authenticates its own input snapshot. */
function authenticateRecovery(plaintext: Uint8Array, independentlySelectedNetwork: unknown, profile: "btc-to-ln/v1" | "ln-to-btc/v1" = "btc-to-ln/v1"): RecoveryRecord {
  try {
    // Validate/snapshot the trust anchor; malformed or absent expectations never select a network for us.
    const network = JSON.parse(new TextDecoder().decode(jcs(independentlySelectedNetwork))) as unknown;
    require(validateNetwork(network));
    const record = parseRecoveryPlaintext(plaintext).document as unknown as RecoveryRecord;
    const terms = record.contract_terms;
    const context = record.verification_context;
    const init = context.handshake_init, accept = context.handshake_accept;
    require(record.profile_id === profile && terms.profile_id === profile && init.profile_id === record.profile_id);
    require([record.network_identity, terms.network_identity, init.network_identity, accept.network_identity].every((item) => same(item, network)));
    checkHandshake(record);
    checkTerms(terms);
    require(context.client_session_xonly_key === init.client_session_xonly_key && context.provider_session_xonly_key === accept.provider_session_xonly_key);
    require(terms.provider_identity_key === init.expected_provider_identity_xonly_key);
    require(new Set([init.client_session_xonly_key, accept.provider_session_xonly_key, terms.provider_identity_key,
      terms.client_contract_compressed_key.slice(2), terms.provider_contract_compressed_key.slice(2), terms.recovery_authorization_xonly_key]).size === 6);
    require(record.contract_hash === bytesToHex(contractHash(terms)));
    require(context.handshake_hash === bytesToHex(handshakeHash(init, accept)));
    verifySchnorr(terms.provider_identity_key, handshakeAcceptHash(accept), context.provider_identity_signature, "handshake");
    verifySchnorr(terms.provider_identity_key, providerTermsHash({ contract_hash: record.contract_hash, contract_terms: terms,
      handshake_hash: context.handshake_hash }), context.provider_terms_signature, "terms");
    verifySchnorr(init.client_session_xonly_key, clientAcceptanceHash({ contract_hash: record.contract_hash,
      handshake_hash: context.handshake_hash, session_id: init.session_id, client_session_xonly_key: init.client_session_xonly_key,
      provider_session_xonly_key: accept.provider_session_xonly_key }), context.client_acceptance_signature, "acceptance");
    require(record.updated_at >= record.created_at && record.chain_scan_birthday_height <= terms.refund_lock_height);
    require(record.recovery_authorization_xonly_key === terms.recovery_authorization_xonly_key);
    require(record.fee_policy.max_claim_fee_sat === terms.max_claim_fee_sat && record.fee_policy.max_refund_fee_sat === terms.max_refund_fee_sat);
    const knowledge = record.monotonic_knowledge;
    require(knowledge.preimage_known === (knowledge.preimage !== null));
    if (profile === "ln-to-btc/v1") require(knowledge.preimage_known);
    if (knowledge.preimage !== null) require(bytesToHex(sha256(hexToBytes(knowledge.preimage))) === terms.invoice_binding.payment_hash);
    // This authentication stage only derives the public point; it never signs.
    const secret = hexToBytes(record.user_secret.contract_secret_key);
    try { require(bytesToHex(secp256k1.getPublicKey(secret, true)) === terms.client_contract_compressed_key); }
    finally { secret.fill(0); }
    const reconstructed = reconstructTaprootContract(terms);
    require((Object.keys(reconstructed) as (keyof TaprootContract)[]).every((field) => record.taproot_contract[field] === reconstructed[field]));
    checkHistory(record);
    if (profile === "btc-to-ln/v1") {
      require(![REVERSE_FALLBACK_EXTENSION, REVERSE_DISCLOSURE_EXTENSION, REVERSE_COOPERATIVE_RESERVATION_EXTENSION].some((key) => Object.hasOwn(record.extensions, key)));
      checkReservation(record);
    } else {
      require(!Object.hasOwn(record.extensions, COOPERATIVE_RESERVATION_EXTENSION));
      if (Object.hasOwn(record.extensions, REVERSE_FALLBACK_EXTENSION)) checkReverseFallback(record);
      checkReverseCooperation(record);
    }
    return record;
  } catch { /* Do not attach errors from parsers, crypto, or secret-bearing documents. */ }
  throw new RecoveryInspectionRefusedError();
}

/** Network selection is external to the document. Success is a redacted report, never spending authority. */
export function inspectRecoveryPlaintext(plaintext: Uint8Array, independentlySelectedNetwork: unknown): RecoveryInspection {
  const record = authenticateRecovery(plaintext, independentlySelectedNetwork);
  return Object.freeze({ verification: "historical-static", networkName: record.network_identity.name,
    destinationScript: record.contract_terms.client_destination_script, maxRefundFeeSat: record.contract_terms.max_refund_fee_sat,
    profileId: "btc-to-ln/v1", contractHash: record.contract_hash, refundLockHeight: record.contract_terms.refund_lock_height,
    firstRefundEligibleHeight: record.contract_terms.refund_lock_height + 1, recordedBindingCount: record.funding_history.length,
    fundingHistory: Object.freeze(record.funding_history.map(({ binding: b }) => Object.freeze({
      contract_hash: b.contract_hash, funding_attempt_id: b.funding_attempt_id, binding_revision: b.binding_revision, funder_role: b.funder_role,
      lineage_anchor_txid: b.lineage_anchor_txid, lineage_anchor_vout: b.lineage_anchor_vout, funding_txid: b.funding_txid,
      contract_vout: b.contract_vout, contract_value_sat: b.contract_value_sat, contract_script_pubkey: b.contract_script_pubkey,
      replaces_txid: b.replaces_txid, created_at: b.created_at,
    }))) });
}

export interface RecoveryDepositTarget {
  readonly contractHash: string;
  readonly scriptPubkey: string;
  readonly nominalValueSat: string;
  readonly birthdayHeight: number;
}

/** Authenticated public discovery hints, never an assertion that funding exists. */
export function inspectRecoveryDepositTarget(
  plaintext: Uint8Array, independentlySelectedNetwork: unknown,
): RecoveryDepositTarget {
  const record = authenticateRecovery(plaintext, independentlySelectedNetwork);
  return Object.freeze({ contractHash: record.contract_hash, scriptPubkey: record.taproot_contract.script_pubkey,
    nominalValueSat: record.contract_terms.economics.contract_amount_sat,
    birthdayHeight: record.chain_scan_birthday_height });
}

export interface RecoveryFundingSelection {
  readonly fundingAttemptId: string;
  readonly bindingRevision: number;
}

/** An explicitly selected actual output, not a revision or a funder declaration. */
export interface RecoveryOutpointSelection {
  readonly kind: "outpoint";
  readonly fundingTxid: string;
  readonly fundingVout: number;
}

export type RecoveryRefundSelection = RecoveryFundingSelection | RecoveryOutpointSelection;
type RecoveryContractOutput = Pick<HistoricalBinding,
  "funding_txid" | "contract_vout" | "contract_value_sat" | "contract_script_pubkey">;

function recoveryOutpoint(record: RecoveryRecord, selection: RecoveryOutpointSelection, raw: Uint8Array): RecoveryContractOutput {
  require(selection.kind === "outpoint" && typeof selection.fundingTxid === "string" && /^[0-9a-f]{64}$/.test(selection.fundingTxid));
  require(Number.isSafeInteger(selection.fundingVout) && selection.fundingVout >= 0 && selection.fundingVout <= 0xffffffff);
  require(raw instanceof Uint8Array && raw.length > 0 && raw.length <= MAX_TRANSACTION_BYTES);
  const transaction = parseRecoveryFundingTransaction(raw), output = transaction.outputs[selection.fundingVout];
  require(transaction.txid === selection.fundingTxid && output !== undefined);
  require(transaction.outputs.reduce((total, item) => total + item.value, 0n) <= MAX_SATS);
  require(new Set(transaction.inputs.map((input) => `${input.txid}:${input.vout}`)).size === transaction.inputs.length);
  require(bytesToHex(output!.script) === record.taproot_contract.script_pubkey);
  return Object.freeze({ funding_txid: transaction.txid, contract_vout: selection.fundingVout,
    contract_value_sat: output!.value.toString(), contract_script_pubkey: record.taproot_contract.script_pubkey });
}

/** Authenticate actual output bytes without inventing signed funding history. No live evidence. */
export function checkRecoveryOutpointTransaction(
  plaintext: Uint8Array, independentlySelectedNetwork: unknown, selection: RecoveryOutpointSelection, rawFundingTransaction: Uint8Array,
): void {
  try {
    require(rawFundingTransaction instanceof Uint8Array && rawFundingTransaction.length > 0 && rawFundingTransaction.length <= MAX_TRANSACTION_BYTES);
    const record = authenticateRecovery(plaintext, independentlySelectedNetwork);
    require(isSupportedRecoveryNetwork(record.network_identity));
    recoveryOutpoint(record, { ...selection }, Uint8Array.from(rawFundingTransaction));
    return;
  } catch { /* Never attach imported-document, parser, or output diagnostics. */ }
  throw new RecoveryInspectionRefusedError();
}

function selectBinding(record: RecoveryRecord, selection: RecoveryFundingSelection): HistoricalBinding {
  const { fundingAttemptId, bindingRevision } = selection;
  require(typeof fundingAttemptId === "string" && /^[0-9a-f]{64}$/.test(fundingAttemptId));
  require(Number.isSafeInteger(bindingRevision) && bindingRevision >= 0 && bindingRevision < 64);
  const matches = record.funding_history.filter(({ binding }) => binding.funding_attempt_id === fundingAttemptId && binding.binding_revision === bindingRevision);
  require(matches.length === 1);
  return matches[0]!.binding;
}

/** Authenticate and check selected funding bytes only. No chain, ownership, or spending authority. */
export function checkSelectedRecoveryFundingTransaction(
  plaintext: Uint8Array, independentlySelectedNetwork: unknown, selection: RecoveryFundingSelection, rawFundingTransaction: Uint8Array,
): void {
  try {
    const chosen = { fundingAttemptId: selection.fundingAttemptId, bindingRevision: selection.bindingRevision };
    require(rawFundingTransaction instanceof Uint8Array && rawFundingTransaction.length > 0 && rawFundingTransaction.length <= MAX_TRANSACTION_BYTES);
    const raw = Uint8Array.from(rawFundingTransaction);
    const record = authenticateRecovery(plaintext, independentlySelectedNetwork);
    require(isSupportedRecoveryNetwork(record.network_identity));
    checkFundingTransaction(raw, selectBinding(record, chosen));
    return;
  } catch { /* No byte-check diagnostics or secret-bearing causes escape. */ }
  throw new RecoveryInspectionRefusedError();
}

export interface SelectedRecoveryRefundInput {
  readonly fundingAttemptId: string;
  readonly bindingRevision: number;
  readonly rawFundingTransaction: Uint8Array;
  /** Caller observation, not a chain proof. Must be freshly checked outside this offline constructor. */
  readonly sampledTipHeight: number;
  readonly feeSat: bigint;
}

export interface ConstructedRecoveryRefund {
  readonly transactionHex: string;
  readonly txid: string;
  readonly contractHash: string;
  readonly fundingTxid: string;
  readonly fundingVout: number;
  readonly destinationScript: string;
  readonly refundLockHeight: number;
  readonly feeSat: string;
  readonly outputValueSat: string;
  readonly vsize: number;
}

export class RecoveryRefundRefusedError extends Error {
  constructor() {
    super("Recovery refund construction refused");
    this.name = "RecoveryRefundRefusedError";
  }
}

/** Core's exact supported execution identities. */
export function isSupportedRecoveryNetwork(value: unknown): boolean {
  try {
    if (!validateNetwork(value)) return false;
    const network = value as RecoveryRecord["network_identity"];
    const supported: Record<string, unknown> = { mainnet, signet, testnet4, regtest };
    if (!Object.hasOwn(supported, network.name)) return false;
    if (network.name === "regtest") return typeof network.deployment_namespace === "string" && network.deployment_namespace.length > 0 &&
      same({ ...network, deployment_namespace: regtest.deployment_namespace }, regtest);
    return same(network, supported[network.name]);
  } catch { return false; }
}

/** Core check_funding_binding_transaction rules, not UTXO, inclusion, or chain evidence. */
function checkFundingTransaction(raw: Uint8Array, binding: HistoricalBinding): void {
  const transaction = parseTransaction(raw);
  require(transaction.txid === binding.funding_txid);
  const inputs = transaction.inputs.map((input) => `${input.txid}:${input.vout}`);
  require(new Set(inputs).size === inputs.length && inputs.includes(`${binding.lineage_anchor_txid}:${binding.lineage_anchor_vout}`));
  require(transaction.inputs.every((input) => input.scriptSig.length === 0));
  let contractOutputs = 0, total = 0n;
  for (const [index, output] of transaction.outputs.entries()) {
    total += output.value;
    const script = bytesToHex(output.script);
    if (script === binding.contract_script_pubkey) {
      require(index === binding.contract_vout && output.value === BigInt(binding.contract_value_sat));
      contractOutputs++;
    } else require(/^(0014[0-9a-f]{40}|5120[0-9a-f]{64})$/.test(script));
  }
  require(contractOutputs === 1 && total <= MAX_SATS);
}

const refundU32 = (value: number): Uint8Array => Uint8Array.of(value & 0xff, (value >>> 8) & 0xff, (value >>> 16) & 0xff, (value >>> 24) & 0xff);
function refundU64(value: bigint): Uint8Array {
  const bytes = new Uint8Array(8);
  for (let i = 0; i < 8; i++) bytes[i] = Number((value >> BigInt(i * 8)) & 0xffn);
  return bytes;
}

/** Our only scripts here are 22/34 bytes, so their canonical CompactSize is one byte. */
const refundScriptBytes = (script: Uint8Array): Uint8Array => {
  require(script.length < 0xfd);
  return concatBytes(Uint8Array.of(script.length), script);
};

/** BIP341 DEFAULT script-path spend (ext_flag 1, input 0, no annex). */
function scriptPathSighash(binding: RecoveryContractOutput, leafHash: string, output: Transaction["outputs"][number], lockHeight: number): Uint8Array {
  const prevout = concatBytes(hexToBytes(binding.funding_txid).reverse(), refundU32(binding.contract_vout));
  const message = concatBytes(
    Uint8Array.of(0x00), // hash_type DEFAULT
    refundU32(2), refundU32(lockHeight),
    sha256(prevout), sha256(refundU64(BigInt(binding.contract_value_sat))),
    sha256(refundScriptBytes(hexToBytes(binding.contract_script_pubkey))),
    sha256(refundU32(0xfffffffd)),
    sha256(concatBytes(refundU64(output.value), refundScriptBytes(output.script))),
    Uint8Array.of(0x02), // spend_type = ext_flag * 2 + annex_present
    refundU32(0),
    hexToBytes(leafHash), Uint8Array.of(0x00), refundU32(0xffffffff),
  );
  return taggedHash("TapSighash", concatBytes(Uint8Array.of(0x00), message));
}

/** Verify every spend byte and its signature against independently authenticated terms. */
function authorizedRefund(record: RecoveryRecord, binding: RecoveryContractOutput, raw: Uint8Array): ConstructedRecoveryRefund {
  const parsed = parseTransaction(raw), terms = record.contract_terms;
  require(parsed.version === 2 && parsed.locktime === terms.refund_lock_height && parsed.inputs.length === 1 && parsed.outputs.length === 1);
  const input = parsed.inputs[0]!, output = parsed.outputs[0]!;
  require(input.txid === binding.funding_txid && input.vout === binding.contract_vout && input.sequence === 0xfffffffd && input.scriptSig.length === 0);
  require(input.witness.length === 3 && input.witness[0]!.length === 64);
  require(bytesToHex(input.witness[1]!) === record.taproot_contract.refund_script && bytesToHex(input.witness[2]!) === record.taproot_contract.refund_control_block);
  require(bytesToHex(output.script) === terms.client_destination_script);
  const fee = BigInt(binding.contract_value_sat) - output.value;
  require(fee >= 0n && fee <= BigInt(terms.max_refund_fee_sat) && output.value >= (output.script.length === 22 ? 294n : 330n));
   require(schnorr.verify(input.witness[0]!, scriptPathSighash(binding, record.taproot_contract.refund_leaf_hash, output, terms.refund_lock_height), hexToBytes(terms.client_contract_compressed_key.slice(2))));
  require(bytesToHex(serializeTransaction(parsed, true)) === bytesToHex(raw));
  const baseSize = serializeTransaction(parsed, false).length;
  return Object.freeze({ transactionHex: bytesToHex(raw), txid: parsed.txid, contractHash: record.contract_hash,
    fundingTxid: binding.funding_txid, fundingVout: binding.contract_vout, destinationScript: terms.client_destination_script,
    refundLockHeight: terms.refund_lock_height, feeSat: fee.toString(), outputValueSat: output.value.toString(),
    vsize: Math.ceil((baseSize * 3 + raw.length) / 4) });
}

/** Reauthorize stored spending bytes, without signing or claiming current spendability. */
export function verifySelectedRecoveryRefund(
  plaintext: Uint8Array, independentlySelectedNetwork: unknown, selection: RecoveryFundingSelection,
  rawFundingTransaction: Uint8Array, signedRefund: Uint8Array,
): ConstructedRecoveryRefund {
  try {
    const chosen = { fundingAttemptId: selection.fundingAttemptId, bindingRevision: selection.bindingRevision };
    require(rawFundingTransaction instanceof Uint8Array && rawFundingTransaction.length > 0 && rawFundingTransaction.length <= MAX_TRANSACTION_BYTES);
    require(signedRefund instanceof Uint8Array && signedRefund.length > 0 && signedRefund.length <= MAX_TRANSACTION_BYTES);
    const funding = Uint8Array.from(rawFundingTransaction), signed = Uint8Array.from(signedRefund);
    const record = authenticateRecovery(plaintext, independentlySelectedNetwork);
    require(isSupportedRecoveryNetwork(record.network_identity));
    const binding = selectBinding(record, chosen);
    checkFundingTransaction(funding, binding);
    return authorizedRefund(record, binding, signed);
  } catch { /* Discard all secret-bearing underlying causes. */ }
  throw new RecoveryRefundRefusedError();
}

/** Reauthorize exact saved refund bytes from authenticated terms and an actual output. */
export function verifyRecoveryOutpointRefund(
  plaintext: Uint8Array, independentlySelectedNetwork: unknown, selection: RecoveryOutpointSelection,
  rawFundingTransaction: Uint8Array, signedRefund: Uint8Array,
): ConstructedRecoveryRefund {
  try {
    require(rawFundingTransaction instanceof Uint8Array && rawFundingTransaction.length > 0 && rawFundingTransaction.length <= MAX_TRANSACTION_BYTES);
    const record = authenticateRecovery(plaintext, independentlySelectedNetwork);
    require(isSupportedRecoveryNetwork(record.network_identity));
    require(signedRefund instanceof Uint8Array && signedRefund.length > 0 && signedRefund.length <= MAX_TRANSACTION_BYTES);
    const output = recoveryOutpoint(record, { ...selection }, Uint8Array.from(rawFundingTransaction));
    return authorizedRefund(record, output, Uint8Array.from(signedRefund));
  } catch { /* No secret-bearing causes escape. */ }
  throw new RecoveryRefundRefusedError();
}

/**
 * Disconnected selected-outpoint BTC to LN refund construction. Reauthenticates
 * bytes and checks the raw funding transaction, never trusts an inspection
 * report. Caller-supplied height is NOT certified chain data. Before invoking
 * this for real funds, independently check funding inclusion, maturity, and
 * mempool-aware unspent state and obtain explicit user approval BEFORE signing.
 * Output is a broadcastable capability, not a report or proof of destination
 * ownership. Recheck before manual broadcast. No storage,
 * network, automatic selection, destination override, or broadcast occurs here.
 */
export function constructSelectedRecoveryRefund(
  plaintext: Uint8Array, independentlySelectedNetwork: unknown, input: SelectedRecoveryRefundInput,
): ConstructedRecoveryRefund {
  try {
    const { fundingAttemptId, bindingRevision, sampledTipHeight, feeSat, rawFundingTransaction } = input;
    require(rawFundingTransaction instanceof Uint8Array && rawFundingTransaction.length > 0 && rawFundingTransaction.length <= MAX_TRANSACTION_BYTES);
    const rawFunding = Uint8Array.from(rawFundingTransaction);
    const record = authenticateRecovery(plaintext, independentlySelectedNetwork);
    require(isSupportedRecoveryNetwork(record.network_identity));
    const binding = selectBinding(record, { fundingAttemptId, bindingRevision });
    checkFundingTransaction(rawFunding, binding);
    return signRecoveryRefund(record, binding, sampledTipHeight, feeSat);
  } catch { /* Never expose document, signer, or parser errors or causes. */ }
  throw new RecoveryRefundRefusedError();
}

export interface RecoveryOutpointRefundInput extends RecoveryOutpointSelection {
  readonly rawFundingTransaction: Uint8Array;
  readonly sampledTipHeight: number;
  readonly feeSat: bigint;
}

/** Separately approved unilateral recovery, independent of provider/funder messages. */
export function constructRecoveryOutpointRefund(
  plaintext: Uint8Array, independentlySelectedNetwork: unknown, input: RecoveryOutpointRefundInput,
): ConstructedRecoveryRefund {
  try {
    const { kind, fundingTxid, fundingVout, sampledTipHeight, feeSat, rawFundingTransaction } = input;
    require(rawFundingTransaction instanceof Uint8Array && rawFundingTransaction.length > 0 && rawFundingTransaction.length <= MAX_TRANSACTION_BYTES);
    const record = authenticateRecovery(plaintext, independentlySelectedNetwork);
    require(isSupportedRecoveryNetwork(record.network_identity));
    const output = recoveryOutpoint(record, { kind, fundingTxid, fundingVout }, Uint8Array.from(rawFundingTransaction));
    return signRecoveryRefund(record, output, sampledTipHeight, feeSat);
  } catch { /* No secret-bearing causes escape. */ }
  throw new RecoveryRefundRefusedError();
}

function signRecoveryRefund(
  record: RecoveryRecord, binding: RecoveryContractOutput, sampledTipHeight: number, feeSat: bigint,
): ConstructedRecoveryRefund {
  let secret: Uint8Array | undefined, auxiliary: Uint8Array | undefined;
  try {
    const terms = record.contract_terms;
    require(Number.isSafeInteger(sampledTipHeight) && sampledTipHeight >= 0 && sampledTipHeight < 500_000_000);
    require(typeof feeSat === "bigint" && feeSat >= 0n && feeSat <= MAX_SATS);
    require(sampledTipHeight > terms.refund_lock_height && feeSat <= BigInt(terms.max_refund_fee_sat));
    const destination = hexToBytes(terms.client_destination_script);
    const dust = destination.length === 22 ? 294n : 330n;
    const value = BigInt(binding.contract_value_sat) - feeSat;
    require(value >= dust);
    const output = { value, script: destination };
    const transaction = { version: 2, locktime: terms.refund_lock_height, outputs: [output], inputs: [
      { txid: binding.funding_txid, vout: binding.contract_vout, scriptSig: new Uint8Array(), sequence: 0xfffffffd, witness: [] as Uint8Array[] },
    ] };
    const digest = scriptPathSighash(binding, record.taproot_contract.refund_leaf_hash, output, terms.refund_lock_height);
    secret = hexToBytes(record.user_secret.contract_secret_key);
    auxiliary = crypto.getRandomValues(new Uint8Array(32));
    const signature = schnorr.sign(digest, secret, auxiliary);
    require(signature.length === 64 && schnorr.verify(signature, digest, hexToBytes(terms.client_contract_compressed_key.slice(2))));
    transaction.inputs[0]!.witness = [signature, hexToBytes(record.taproot_contract.refund_script), hexToBytes(record.taproot_contract.refund_control_block)];
    const signed = serializeTransaction(transaction, true);
    return authorizedRefund(record, binding, signed);
  } finally { secret?.fill(0); auxiliary?.fill(0); }
}

export const REVERSE_FALLBACK_EXTENSION = "rillswap/reverse-claim-fallback";
export const REVERSE_DISCLOSURE_EXTENSION = "rillswap/reverse-preimage-disclosure";
export const REVERSE_COOPERATIVE_RESERVATION_EXTENSION = "rillswap/reverse-cooperative-reservation";
export interface ReverseRecoveryInspection {
  readonly verification: "historical-static";
  readonly networkName: string;
  readonly profileId: "ln-to-btc/v1";
  readonly contractHash: string;
  readonly destinationScript: string;
  readonly nominalPayoutSat: string;
  readonly claimFeeReserveSat: string;
  readonly maxClaimFeeSat: string;
  readonly refundLockHeight: number;
  readonly claimConfirmationBlocks: number;
  readonly minFundingDepth: number;
  readonly fundingHistory: readonly RecoveryFundingBinding[];
  readonly fallbackTxid: string | null;
  readonly fallbackFeeSat: string | null;
}

export function inspectReverseRecoveryPlaintext(plaintext: Uint8Array, independentlySelectedNetwork: unknown): ReverseRecoveryInspection {
  const record = authenticateRecovery(plaintext, independentlySelectedNetwork, "ln-to-btc/v1"), terms = record.contract_terms as LnToBtcTerms;
  const fallback = Object.hasOwn(record.extensions, REVERSE_FALLBACK_EXTENSION) ? checkReverseFallback(record) : null;
  return Object.freeze({ verification: "historical-static", networkName: record.network_identity.name, profileId: "ln-to-btc/v1",
    contractHash: record.contract_hash, destinationScript: terms.client_destination_script, nominalPayoutSat: terms.economics.nominal_payout_sat,
    claimFeeReserveSat: terms.economics.claim_fee_reserve_sat, maxClaimFeeSat: terms.max_claim_fee_sat, refundLockHeight: terms.refund_lock_height,
    claimConfirmationBlocks: terms.timing_policy.claim_confirmation_blocks, minFundingDepth: terms.funding_confirmations,
    fundingHistory: Object.freeze(record.funding_history.map(({ binding }) => Object.freeze({ ...binding }))), fallbackTxid: fallback?.txid ?? null, fallbackFeeSat: fallback?.feeSat ?? null });
}

export interface SelectedReverseClaimInput extends SelectedRecoveryRefundInput {
  /** Caller observation, not a chain proof. Fresh independent API consistency checks are mandatory. */
  readonly confirmations: number;
  /** The client's explicit lower claim depth (0: mempool), at most the signed one. Absent: the signed depth. */
  readonly minFundingConfirmations?: number;
}
export interface ConstructedReverseClaim extends Omit<ConstructedRecoveryRefund, "refundLockHeight"> {
  readonly signatureHash: string;
}
export class ReverseClaimRefusedError extends Error {
  constructor() { super("Reverse claim construction or verification refused"); this.name = "ReverseClaimRefusedError"; }
}

/** Exact locktime-zero claim leaf, never the refund leaf or cooperative key path. */
function authorizedClaim(record: RecoveryRecord, binding: HistoricalBinding, raw: Uint8Array): ConstructedReverseClaim {
  const terms = record.contract_terms as LnToBtcTerms, parsed = parseTransaction(raw);
  require(terms.profile_id === "ln-to-btc/v1" && parsed.version === 2 && parsed.locktime === 0 && parsed.inputs.length === 1 && parsed.outputs.length === 1);
  const input = parsed.inputs[0]!, output = parsed.outputs[0]!;
  require(input.txid === binding.funding_txid && input.vout === binding.contract_vout && input.sequence === 0xfffffffd && input.scriptSig.length === 0);
  require(input.witness.length === 4 && input.witness[0]!.length === 64 && input.witness[1]!.length === 32);
  require(bytesToHex(input.witness[1]!) === record.monotonic_knowledge.preimage && bytesToHex(sha256(input.witness[1]!)) === terms.invoice_binding.payment_hash);
  require(bytesToHex(input.witness[2]!) === record.taproot_contract.claim_script && bytesToHex(input.witness[3]!) === record.taproot_contract.claim_control_block);
  require(bytesToHex(output.script) === terms.client_destination_script);
  const fee = BigInt(binding.contract_value_sat) - output.value;
  require(fee >= 0n && fee <= BigInt(terms.max_claim_fee_sat) && fee <= BigInt(terms.economics.claim_fee_reserve_sat) &&
    output.value >= BigInt(terms.economics.nominal_payout_sat) && output.value >= (output.script.length === 22 ? 294n : 330n));
  const signatureHash = scriptPathSighash(binding, record.taproot_contract.claim_leaf_hash, output, 0);
  require(schnorr.verify(input.witness[0]!, signatureHash, hexToBytes(terms.client_contract_compressed_key.slice(2))));
  require(bytesToHex(serializeTransaction(parsed, true)) === bytesToHex(raw));
  const baseSize = serializeTransaction(parsed, false).length;
  return Object.freeze({ transactionHex: bytesToHex(raw), txid: parsed.txid, contractHash: record.contract_hash,
    fundingTxid: binding.funding_txid, fundingVout: binding.contract_vout, destinationScript: terms.client_destination_script,
    feeSat: fee.toString(), outputValueSat: output.value.toString(), vsize: Math.ceil((baseSize * 3 + raw.length) / 4), signatureHash: bytesToHex(signatureHash) });
}

function checkReverseFallback(record: RecoveryRecord): ConstructedReverseClaim {
  const fallback = record.extensions[REVERSE_FALLBACK_EXTENSION] as { version: number; funding_binding_hash: string; transaction: string };
  require(fallback !== null && typeof fallback === "object" && Object.keys(fallback).length === 3 && fallback.version === 1);
  const matches = record.funding_history.filter(({ binding }) => bytesToHex(fundingBindingHash(binding)) === fallback.funding_binding_hash);
  require(matches.length === 1); return authorizedClaim(record, matches[0]!.binding, hexToBytes(fallback.transaction));
}

export function checkSelectedReverseFundingTransaction(plaintext: Uint8Array, independentlySelectedNetwork: unknown,
  selection: RecoveryFundingSelection, rawFundingTransaction: Uint8Array): void {
  try {
    const chosen = { fundingAttemptId: selection.fundingAttemptId, bindingRevision: selection.bindingRevision };
    require(rawFundingTransaction instanceof Uint8Array && rawFundingTransaction.length > 0 && rawFundingTransaction.length <= MAX_TRANSACTION_BYTES);
    const raw = Uint8Array.from(rawFundingTransaction), record = authenticateRecovery(plaintext, independentlySelectedNetwork, "ln-to-btc/v1");
    require(isSupportedRecoveryNetwork(record.network_identity)); checkFundingTransaction(raw, selectBinding(record, chosen)); return;
  } catch { throw new RecoveryInspectionRefusedError(); }
}

/** Reauthorizes saved bytes without re-signing, inclusion/depth assertions, or exposure permission. */
export function verifySelectedReverseClaim(plaintext: Uint8Array, independentlySelectedNetwork: unknown, selection: RecoveryFundingSelection,
  rawFundingTransaction: Uint8Array, signedClaim: Uint8Array): ConstructedReverseClaim {
  try {
    const chosen = { fundingAttemptId: selection.fundingAttemptId, bindingRevision: selection.bindingRevision };
    require(rawFundingTransaction instanceof Uint8Array && rawFundingTransaction.length > 0 && rawFundingTransaction.length <= MAX_TRANSACTION_BYTES);
    require(signedClaim instanceof Uint8Array && signedClaim.length > 0 && signedClaim.length <= MAX_TRANSACTION_BYTES);
    const raw = Uint8Array.from(rawFundingTransaction), signed = Uint8Array.from(signedClaim), record = authenticateRecovery(plaintext, independentlySelectedNetwork, "ln-to-btc/v1");
    require(isSupportedRecoveryNetwork(record.network_identity)); const binding = selectBinding(record, chosen);
    checkFundingTransaction(raw, binding); return authorizedClaim(record, binding, signed);
  } catch { throw new ReverseClaimRefusedError(); }
}

/**
 * Signs a preimage-revealing capability. Caller MUST approve destination/fee and
 * freshly check actual unspent funding/depth/height BEFORE invocation. It must
 * persist these exact bytes and separately authorize exposure before any export
 * or broadcast. Observations below are bounded caller assertions, not proofs.
 */
export function constructSelectedReverseClaim(plaintext: Uint8Array, independentlySelectedNetwork: unknown, input: SelectedReverseClaimInput): ConstructedReverseClaim {
  let secret: Uint8Array | undefined, auxiliary: Uint8Array | undefined;
  try {
    const { fundingAttemptId, bindingRevision, sampledTipHeight: tip, confirmations, feeSat, rawFundingTransaction, minFundingConfirmations } = input;
    require(rawFundingTransaction instanceof Uint8Array && rawFundingTransaction.length > 0 && rawFundingTransaction.length <= MAX_TRANSACTION_BYTES);
    const raw = Uint8Array.from(rawFundingTransaction), record = authenticateRecovery(plaintext, independentlySelectedNetwork, "ln-to-btc/v1");
    require(isSupportedRecoveryNetwork(record.network_identity));
    const binding = selectBinding(record, { fundingAttemptId, bindingRevision }), terms = record.contract_terms as LnToBtcTerms;
    checkFundingTransaction(raw, binding);
    const minimum = minFundingConfirmations ?? terms.funding_confirmations;
    require(Number.isSafeInteger(minimum) && minimum >= 0 && minimum <= terms.funding_confirmations);
    require(Number.isSafeInteger(tip) && tip > 0 && tip < 500000000 && Number.isSafeInteger(confirmations) && confirmations >= minimum && confirmations <= tip + 1);
    require(tip + terms.timing_policy.claim_confirmation_blocks < terms.refund_lock_height + 1);
    require(typeof feeSat === "bigint" && feeSat >= 0n && feeSat <= BigInt(terms.max_claim_fee_sat) && feeSat <= BigInt(terms.economics.claim_fee_reserve_sat));
    const output = { value: BigInt(binding.contract_value_sat) - feeSat, script: hexToBytes(terms.client_destination_script) };
    require(output.value >= BigInt(terms.economics.nominal_payout_sat) && output.value >= (output.script.length === 22 ? 294n : 330n));
    const signatureHash = scriptPathSighash(binding, record.taproot_contract.claim_leaf_hash, output, 0);
    secret = hexToBytes(record.user_secret.contract_secret_key); auxiliary = crypto.getRandomValues(new Uint8Array(32));
    const signature = schnorr.sign(signatureHash, secret, auxiliary);
    const transaction = { version: 2, locktime: 0, outputs: [output], inputs: [
      { txid: binding.funding_txid, vout: binding.contract_vout, scriptSig: new Uint8Array(), sequence: 0xfffffffd,
        witness: [signature, hexToBytes(record.monotonic_knowledge.preimage!), hexToBytes(record.taproot_contract.claim_script), hexToBytes(record.taproot_contract.claim_control_block)] },
    ] };
    return authorizedClaim(record, binding, serializeTransaction(transaction, true));
  } catch { /* Discard secret-bearing signer, parser, or byte diagnostics. */ }
  finally { secret?.fill(0); auxiliary?.fill(0); }
  throw new ReverseClaimRefusedError();
}

/** Secret-bearing native RS-007 successor bytes, for local encryption only. Funded predecessor stays separately durable. */
export function appendReverseClaimFallback(plaintext: Uint8Array, independentlySelectedNetwork: unknown, signedClaim: Uint8Array): Uint8Array {
  try {
    require(signedClaim instanceof Uint8Array && signedClaim.length > 0 && signedClaim.length <= MAX_TRANSACTION_BYTES);
    const signed = Uint8Array.from(signedClaim), record = authenticateRecovery(plaintext, independentlySelectedNetwork, "ln-to-btc/v1");
    require(isSupportedRecoveryNetwork(record.network_identity) && record.funding_history.length > 0 && !Object.hasOwn(record.extensions, REVERSE_FALLBACK_EXTENSION));
    const latest = record.funding_history.at(-1)!.binding; authorizedClaim(record, latest, signed);
    const document = { ...parseRecoveryPlaintext(plaintext).document, extensions: { ...record.extensions,
      [REVERSE_FALLBACK_EXTENSION]: { version: 1, funding_binding_hash: bytesToHex(fundingBindingHash(latest)), transaction: bytesToHex(signed) } } };
    const bytes = new TextEncoder().encode(new TextDecoder().decode(jcs(document))); authenticateRecovery(bytes, independentlySelectedNetwork, "ln-to-btc/v1"); return bytes;
  } catch { throw new RecoveryInspectionRefusedError(); }
}
